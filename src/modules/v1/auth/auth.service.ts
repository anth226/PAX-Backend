import { HttpStatus, Injectable, UnauthorizedException, HttpException, MethodNotAllowedException, BadRequestException } from '@nestjs/common';
import {InjectRepository} from '@nestjs/typeorm';
import { Connection, MoreThan, Repository } from 'typeorm';
import { UserEntity } from '../users/entity/user.entity';
import { OTPEntity } from './entity/otp.entity';
import { RefreshTokenSessionsEntity } from './entity/refresh-token.entity';
import { UserRoleEntity } from '../roles/entity/user-role.entity';
import * as bcrypt from 'bcryptjs';
import { UserDto } from '../users/dto/user.dto';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import * as jwt from 'jsonwebtoken';
import { MailService } from '../mail/mail.service';
import { PhoneService } from '../phone/phone.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginAttemptEntity } from './entity/login-attempt.entity';
import { LoggingService } from './login-logging.service';
import { TwoFactorMethodEntity } from './entity/two-factor.entity';
import { InjectRedis, Redis } from "@nestjs-modules/ioredis";
import { RateLimiterRedis} from "rate-limiter-flexible";
import {Request} from 'express'
import { UpdatePasswordDto } from './entity/dto/update-password.dto';
var CryptoJS = require("crypto-js");
import parsePhoneNumber from 'libphonenumber-js'


const softLockoutTime = Number(process.env.SOFT_PW_LOCKOUT_MINUTES) || 5;
const softLockoutTries = Number(process.env.SOFT_PW_LOCKOUT_TRIES) || 5;
const hardLockoutTime = Number(process.env.HARD_PW_LOCKOUT_HOURS) || 1;
const hardLockoutTries = Number(process.env.HARD_PW_LOCKOUT_TRIES) || 20;


@Injectable()
export class AuthService {
    private softLoginLimit;
    private hardLoginLimit;
  constructor(
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
    @InjectRepository(UserRoleEntity) private readonly userRoleModel: Repository<UserRoleEntity>,
    @InjectRepository(OTPEntity) private readonly otpModel: Repository<OTPEntity>,
    @InjectRepository(LoginAttemptEntity) private readonly loginAttemptModel: Repository<LoginAttemptEntity>,
    @InjectRepository(TwoFactorMethodEntity) private readonly towFaModel: Repository<TwoFactorMethodEntity>,
    @InjectRepository(RefreshTokenSessionsEntity)
    private readonly tokenModel: Repository<RefreshTokenSessionsEntity>,
    // private roleService: RoleService,
    private jwtService: JwtService,
    private mailService: MailService,
    private phoneService: PhoneService,
    // private readonly client: TwilioClient,
    private connection: Connection, // TypeORM transactions.
    private readonly loggingService: LoggingService,
    @InjectRedis() private readonly redis: Redis
  ) {
    this.softLoginLimit = new RateLimiterRedis({
      storeClient: this.redis,
      keyPrefix: 'login_fail_soft',
      points: softLockoutTries,
      duration: softLockoutTime*60,
      blockDuration: softLockoutTime*60, // Block for X minutes
    })
    this.hardLoginLimit = new RateLimiterRedis({
      storeClient: this.redis,
      keyPrefix: 'login_fail_hard',
      points: hardLockoutTries,
      duration: hardLockoutTime*60*60,
      blockDuration: hardLockoutTime*60*60, // Block for X minutes
    })
  }

    async register(userData:CreateUserDto) {
        const isNumberValid = this.isPhoneNumberValid(userData.phone)
        if(!isNumberValid) {
            throw new BadRequestException('Phone Number is not valid.');
        }
        const user = await this.userModel.findOneBy({email: userData.email});
        if (user) {
            throw new BadRequestException('email already exists.');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(userData.password, salt);
        const activationLink = uuidv4();
        await this.userModel.insert({
            email:userData.email,
            password: hashPassword,
            isActivated: false,
            phone: userData.phone ?? null,
            activationLink
        })
        const link = `${process.env.CLIENT_URL}/signin/activate?code=${activationLink}`
        await this.mailService.sendActivationMail(userData.email, link, userData.password)
        return userData;
    }

    async checkEmail(userData:any) {
        try {
            return await this.getUserByEmail(userData.email)
        } catch (error) {
            throw new HttpException(error.message, 500)
        }
    }

    async login(req: Request, userData: any, ip: string, ua: string, method: string) {
        try {
            const user: UserEntity = await this.validateUser(userData, ip);
            if (user.banned) {
                throw new UnauthorizedException({
                    message: `You are banned`,
                });
            }
            if (!user.isActivated) {
                throw new HttpException("User is not activated.", HttpStatus.BAD_REQUEST)
            }
            await this.removeLimit(user.email, ip)
            const hasNextPage = this.checkHasNextPage(req, "password", new UserDto(user))
            if (hasNextPage) return hasNextPage;
            await this.loggingService.logSuccessfulLogin(user, ip, ua, method, false)
            const userDataAndTokens = await this.tokenSession(req, user, ip);
            return userDataAndTokens;
        } catch (error) {
            throw new HttpException(error.response ?? error, error.status ?? 500)
        }
    }

    async validateUser(userData: any, ip: string): Promise<any> {
        try {
            const user = await this.getUserByEmail(userData.email);
            if (!user) {
                throw new HttpException({
                    message: `User with email ${userData.email} not found`,
                }, HttpStatus.BAD_REQUEST);
            }
            var bytes  = CryptoJS.AES.decrypt(userData.password, process.env.PASSWORD_DECRYPTION_KEY ?? "");
            userData.password = bytes.toString(CryptoJS.enc.Utf8);
            const isPasswordEquals = await bcrypt.compare(userData.password, user.password);
            if (!isPasswordEquals) {
                // Consume 1 point from limiters on wrong attempt and block if limits reached
                await Promise.all([
                  this.softLoginLimit.consume(this.getUsernameIPkey(user.email, ip)),
                  this.hardLoginLimit.consume(ip)
                ])
                throw new HttpException({ message: `Incorrect Password`, isPasswordFailed: true }, HttpStatus.BAD_REQUEST);
            }
            const { password, ...result } = user;
            return result;
        } catch (error) {
            if(error?.msBeforeNext) {
                throw new HttpException({"message": "Too Many Requests", msBeforeNext: error.msBeforeNext}, 429);
            }
            throw error;
        }
    }

    async turnOnTwoFactorAuthentication(userId: number) {
        const user = await this.userModel.findOneBy({id: userId})
        if(!user) {
            throw new UnauthorizedException({
                message: 'The user with the given ID is not in the database',
            });
        }
        user.isTwoFactorAuthenticationEnabled = true;
        await user.save();
        return;
    }

    async addTwoFactorAuthenticationMethod(userId:number, methodType:string, methodDetail: string) {
        const user = await this.userModel.findOne({where: {id: userId}, relations:["twoFactorMethods"]})
        if(!user) {
            throw new UnauthorizedException({
                message: 'The user with the given ID is not in the database',
            });
        }
        let method = user.twoFactorMethods.find(method => method.methodType === methodType);
        if(method) {
            method.methodDetail = methodDetail
        } else {
            // Method doesn't exist, create a new entry
            method = new TwoFactorMethodEntity();
            method.methodType = methodType;
            method.methodDetail = methodDetail;
            method.user = user;
            user.twoFactorMethods.push(method);
            user.defaultTwoFactorMethod = method
        }
        await this.userModel.save(user);
        return;
    }

    async tokenSession(req: Request, userData: any, ip: string) {
        if (!userData) {
            throw new UnauthorizedException({
                message: 'The user with the given ID is not in the database',
            });
        }
        // pulling out roles for results
        // if (!userData.roles) {
        //     const userRoles = await this.connection.getRepository(UserRoleEntity).createQueryBuilder('user-roles').innerJoinAndSelect('user-roles.role', 'role').where('user-roles.userId = :id', {id: userData.id}).getMany()
        //     userData.roles = userRoles.map(userRoles => userRoles.role);
        // }
        const userDto = new UserDto(userData);
        const tokens = await this.generateToken({ ...userDto });
        await this.saveToken(req, {accessToken: tokens.accessToken, refreshToken:tokens.refreshToken});
        return {
            statusCode: HttpStatus.OK,
            message: 'User information',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken, // refresh token only for mobile app
            user: userDto,
        };
    }

    async getUserByEmail(email: string) {
        const user = await this.userModel.findOne({where: {email}, relations:['loginAttempts']});
        return user;
    }

    async limitLogin(username:string, ip:string) {
        const usernameIPkey = this.getUsernameIPkey(username, ip)
        const [softLimitResponse, hardLimitResponse] = await Promise.all([
            this.softLoginLimit.get(usernameIPkey),
            this.hardLoginLimit.get(ip)
        ]);
        if(softLimitResponse && softLimitResponse.consumedPoints>softLockoutTries) {
            throw new HttpException({"message": "Too Many Requests", msBeforeNext: softLimitResponse.msBeforeNext}, 429);
        }
        if(hardLimitResponse && hardLimitResponse.consumedPoints>hardLockoutTries) {
            throw new HttpException({"message": "Too Many Requests", msBeforeNext: hardLimitResponse.msBeforeNext}, 429);
        }
        return;
    }

    async removeLimit(username:string, ip:string) {
        const usernameIPkey = this.getUsernameIPkey(username, ip)
        await this.softLoginLimit.delete(usernameIPkey);
    }

    async removeHardLimit(ip:string) {
        await this.softLoginLimit.delete(ip);
    }

    getUsernameIPkey(username: string, ip: string): string {
        return`${username}_${ip}`;
    }

    async generateToken(user: any) {
        const payload = { email: user.email, id: user.id, roles: user.roles };
        const accessToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_ACCESS_SECRET,
            expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        });
        const refreshToken = this.jwtService.sign(payload, {
            secret: process.env.JWT_REFRESH_SECRET,
            expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
        });
        return {
            accessToken,
            refreshToken,
        };
    }

    async savePreAuthToken(
        req: Request,
        payload: any
    ) {
        const token = this.jwtService.sign(payload, {
            secret: process.env.JWT_ACCESS_SECRET,
            expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        });
        req.res.cookie('pre_auth_token', token, {
            maxAge: 1000 * 60 * 60 * 1,
            httpOnly: true,
            sameSite: 'none',
            domain: 'localhost',
            secure: true
        });
    }

    async saveToken(
        req: Request,
        { accessToken, refreshToken }: { accessToken: string, refreshToken?: string}
    ) {
        const domain = process.env.MAIN_DOMAIN || "paxtraining.com"
        req.res.cookie('access_token', accessToken, {
            maxAge: 1000 * 60 * 60 * 1,
            httpOnly: true,
            sameSite: 'lax',
            domain: `.${domain}`, // Replace with your desired domain
            secure: true
        });

        if (refreshToken) {
            req.res.cookie('refresh_token', refreshToken, {
                maxAge: 1000 * 60 * 60 * 24 * 30,
                httpOnly: true,
                sameSite: 'lax',
                domain: `.${domain}`, // Replace with your desired domain
                secure: true
            });
        }
        return
    }

    async removeToken(refreshToken: string) {
        const tokenData = await this.tokenModel.delete({ refreshToken });
        return tokenData;
    }

    async generateOtpMail(email: string)
    {
        const user = await this.userModel.findOneBy({email})
        if(!user) {
            throw new HttpException({
                message: `Invalid Email`,
            }, HttpStatus.BAD_REQUEST);
        }

        const otpCode: string = this.generateOTP(6)
        const now = new Date();
        let currentTime = new Date().getTime();
        const otpExists = await this.otpModel.findOneBy({email})
        if(otpExists) {
            let diff: number = Number(otpExists.resendIn) - currentTime;
            if(diff>0) {
                throw new HttpException({
                    message: `You've already generated OTP Code. Please try again afte ${this.formatTimeDuration(diff)}`,
                    resendIn: Math.floor(diff/1000),
                }, HttpStatus.BAD_REQUEST);
            }
        }

        const expirationInMinute = Number(process.env.OTP_VALID_MINUTES) || 10;
        const expiresIn = String(now.getTime() + (expirationInMinute * 60000));
        const resendInMinute = Number(process.env.OTP_RESEND_MINUTES) || 2;
        const resendIn = String(now.getTime() + (resendInMinute * 60000));
        await this.mailService.sendMailCode(email, otpCode);
        if(otpExists) {
            otpExists.code = otpCode;
            otpExists.expiresIn = expiresIn;
            otpExists.resendIn = resendIn;
            await otpExists.save()
        } else {
            await this.otpModel.insert({
                code: otpCode,
                expiresIn: expiresIn,
                email: email,
                identifier: otpCode,
                resendIn: resendIn
            })
        }
        let diff: number = Number(resendIn) - currentTime;
        return {
            email:email,
            resendIn: Math.floor(diff/1000)
        }
    }

    async verifyOtpMail(
        req: Request,
        email: string,
        code: string,
        ip: string,
        ua: string,
        method: string,
    ) {
        try {
            code = this.decryptCryptoJS(code)
            const user = await this.userModel.findOneBy({email});
            if(!user) {
                throw new HttpException("Email doesn't exists", HttpStatus.BAD_REQUEST)
            }
            const otp = await this.otpModel.findOneBy({email})
            if(!otp) {
                throw new HttpException("No OTP Code associated with this email.", HttpStatus.BAD_REQUEST)
            }
    
            if(otp.code!=code) {
                throw new HttpException("Invalid OTP Code", HttpStatus.BAD_REQUEST)
            }
    
            let currentTime = new Date().getTime();
            let diff: number = Number(otp.expiresIn) - currentTime;
            if(diff<0) {
                // code expired
                throw new HttpException("OTP Code Expired", HttpStatus.BAD_REQUEST)
            }
            user.isActivated = true
            await user.save()
            await otp.remove()
            this.removeLimit(email, ip)
            const hasNextPage = this.checkHasNextPage(req, "2fa", new UserDto(user))
            if (hasNextPage) return hasNextPage;
            await this.loggingService.logSuccessfulLogin(user, ip, ua, method, true)
            return await this.tokenSession(req, user, ip)
        } catch (error) {
            try {
                // Consume 1 point from limiters on wrong attempt and block if limits reached
                await Promise.all([
                    this.softLoginLimit.consume(this.getUsernameIPkey(email, ip)),
                    this.hardLoginLimit.consume(ip)
                ])
            } catch (tlError) {
                if(tlError?.msBeforeNext) {
                    throw new HttpException({"message": "Too Many Requests", msBeforeNext: tlError.msBeforeNext}, 429);
                }
            }
            throw error
        }
    }

    async requirePassReset(
        req: Request,
        userDto: any,
        body: UpdatePasswordDto,
        ip: string,
        ua: string,
        method: string,
    ) {
        this.updatePassword(userDto?.email, body.current_password, body.new_password, ip)
        const hasNextPage = this.checkHasNextPage(req, "password-reset", userDto)
        if (hasNextPage) return hasNextPage;
        const user = await this.userModel.findOneBy({id:userDto.id})
        await this.loggingService.logSuccessfulLogin(user, ip, ua, method, false)
        const userDataAndTokens = await this.tokenSession(req, user, ip);
        return userDataAndTokens;
    }

    async updatePassword(
        email: string,
        current_password: string,
        new_password: string,
        ip: string
    ) {
        const userData = {email, password: current_password}
        const user = await this.validateUser(userData, ip)
        if (user.banned) {
            throw new UnauthorizedException({
                message: `You are banned`,
            });
        }
        if (!user.isActivated) {
            throw new HttpException("User is not activated.", HttpStatus.BAD_REQUEST)
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(new_password, salt);
        return await this.userModel.update({id: user.id}, {password: hashPassword})
    }

    async checkHasNextPage(req: Request, currentPage: string, user: UserDto) {
        let nextPage: string | null = null;
        if(currentPage=="password" && user?.isTwoFactorAuthenticationEnabled) {
            const payload = {id:user.id, email:user.email}
            this.savePreAuthToken(req, payload)
            nextPage = "2fa";
        } else if(currentPage!="password-reset" && user?.requirePassReset) {
            if(!req.cookies?.pre_auth_token) {
                const payload = {id:user.id, email:user.email}
                this.savePreAuthToken(req, payload)
            }
            nextPage = "password-reset";
        } else if(!user?.hasAcceptedLatestTOS) {
            if(!req.cookies?.pre_auth_token) {
                const payload = {id:user.id, email:user.email}
                this.savePreAuthToken(req, payload)
            }
            nextPage = "agreement";
        }
        if(nextPage) {
            return {
                statusCode: HttpStatus.OK,
                message: 'User information',
                user: user,
                nextPage
            };
        }
        return null;
    }

    async activateAccount(activationLink: string): Promise<any> {
        const user = await this.userModel.findOneBy({ activationLink });
        if (!user) {
            throw new HttpException(`Invalid activation link`, HttpStatus.BAD_REQUEST);
        }
        user.isActivated = true;
        await user.save();
        return user;
    }

    async resetPassword(email: any) {
        const user = await this.getUserByEmail(email);
        if (!user) {
            throw new HttpException('Email not found in our database.', HttpStatus.BAD_REQUEST);
        }
        if (!user.isActivated) {
            throw new MethodNotAllowedException();
        }
        const linkReset = uuidv4();
        const forgotLink = `${process.env.CLIENT_URL}/resetpwd?link=${linkReset}`;
        await this.mailService.sendMailPasswordCreation(email, forgotLink);

        const now = new Date();
        const expirationInHours = Number(process.env.RESET_LINK_EXPIRE_HOURS) ?? 24;
        const expirationInMinute = expirationInHours*60;
        const expiresIn = String(now.getTime() + (expirationInMinute * 60000));

        user.resetLinkExpiresIn = expiresIn
        user.resetLink = linkReset
        await user.save()
        return;
    }

    decryptCryptoJS(value: string) {
        try {
            const decryptedValue = CryptoJS.AES.decrypt(value, process.env.PASSWORD_DECRYPTION_KEY ?? "").toString(CryptoJS.enc.Utf8);
            if(!decryptedValue) {
              throw new BadRequestException("input is not in right format.");
            }
            return decryptedValue;
        } catch(err) {
            throw err;
        }
    }

    async checkResetPassword(resetLink: any) {
        const user = await this.userModel.findOneBy({resetLink});
        if (!user) {
            throw new BadRequestException('Invalid Reset Link');
        }
        if (resetLink && user.resetLink !== resetLink) {
            throw new BadRequestException('Invalid Reset Link');
        }
        let currentTime = new Date().getTime();
        let diff: number = Number(user.resetLinkExpiresIn) - currentTime;
        if(diff<=0) {
            throw new BadRequestException('Reset link is expired. Please try again.');
        }
        return;
    }

    async newResetPassword(password: string, confirm_password: string, resetLink: string) {
        const decryptedPassword = this.decryptCryptoJS(password)
        const decryptedConfirmPassword = this.decryptCryptoJS(confirm_password)
        // Manually validate the password and confirm_password fields
        if (decryptedPassword !== decryptedConfirmPassword) {
          throw new BadRequestException('Password and Confirm Password do not match');
        }
        const user = await this.userModel.findOneBy({resetLink});
        if (!user) {
            throw new BadRequestException('Invalid link');
        }
        let currentTime = new Date().getTime();
        let diff: number = Number(user.resetLinkExpiresIn) - currentTime;
        if(diff<=0) {
            throw new BadRequestException('Reset link is expired. Please try again.');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(decryptedPassword, salt);
        user.password = hashPassword;
        user.resetLink = null;
        await user.save();
        return;
    }

    async refreshToken(
        req: Request,
        refreshtoken: string,
        ip: string,
    ) {
        if (!refreshtoken) {
            throw new UnauthorizedException({ message: 'User not authorized' });
        }
        const userData = this.validateRefreshToken(refreshtoken);
        const tokenDb = await this.findToken(refreshtoken);
        if (!tokenDb) {
            throw new UnauthorizedException({
                message:
                'refreshToken service: refresh token not found.',
            });
        }
        const user = await this.userModel.findOne(userData.id);
        if (user.banned){
            throw new UnauthorizedException({message: `User is banned.`});
        }
        const userDataAndTokens = await this.tokenSession(req, user, ip);
        return userDataAndTokens;
    }

    private validateRefreshToken(token: string) {
        try {
            const userData = this.jwtService.verify(token, {
                secret: process.env.JWT_REFRESH_SECRET,
            });
            return userData;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                this.removeToken(token);
                throw new HttpException(`Refresh token has expired`, HttpStatus.BAD_REQUEST);
            }
            if (error instanceof jwt.JsonWebTokenError) {
                throw new HttpException(`Invalid refresh token format`, HttpStatus.BAD_REQUEST);
            }
            throw new HttpException(`Server Error`, HttpStatus.BAD_REQUEST);
        }
    }

    private async findToken(refreshToken: string) {
        try {
            const tokenData = await this.tokenModel.findOneBy({ refreshToken });
            return tokenData;
        } catch (error) {
            throw new UnauthorizedException({
                message: 'findToken service: Refresh token not found',
            });
        }
    }

    private generateOTP(length=4) {
        const chars = '0123456789';
        const charsLength = chars.length;
        let otp = '';

        for (let i = 0; i < length; i++) {
            const randomIndex = Math.floor(Math.random() * charsLength);
            otp += chars[randomIndex];
        }

        return otp;
    }

    private formatTimeDuration(timeDifference:number) {
        const minutes = Math.floor(timeDifference / (1000 * 60));
        const seconds = Math.floor((timeDifference % (1000 * 60)) / 1000);

        if (minutes > 0) {
            return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        } else {
            return `${seconds} second${seconds !== 1 ? 's' : ''}`;
        }
    }

    isPhoneNumberValid(phone: string) {
        return parsePhoneNumber(phone);
    }

    async testSend(target, message="hello") {
        return target;
    }


    async sendOtpPhone(TARGET_PHONE_NUMBER: string) {
        const user = await this.userModel.findOneBy({phone:TARGET_PHONE_NUMBER})
        if(!user) {
            throw new HttpException({
                message: `Invalid Email`,
            }, HttpStatus.BAD_REQUEST);
        }

        const otpCode: string = this.generateOTP(6)

        const message = `Your PAX Training Code is: ${otpCode} \n\nDon't share it with anyone. \n\n@${process.env.MAIN_DOMAIN} https://${process.env.MAIN_DOMAIN}`

        const now = new Date();
        let currentTime = new Date().getTime();
        const otpExists = await this.otpModel.findOneBy({phone:TARGET_PHONE_NUMBER})
        if(otpExists) {
            let diff: number = Number(otpExists.resendIn) - currentTime;
            if(diff>0) {
                throw new HttpException({
                    message: `You've already generated OTP Code. Please try again afte ${this.formatTimeDuration(diff)}`,
                    resendIn: Math.floor(diff/1000),
                }, HttpStatus.BAD_REQUEST);
            }
        }
        await this.phoneService.sendPhoneSMS(TARGET_PHONE_NUMBER, message);

        const expirationInMinute = Number(process.env.OTP_VALID_MINUTES) || 10;
        const expiresIn = String(now.getTime() + (expirationInMinute * 60000));
        const resendInMinute = Number(process.env.OTP_RESEND_MINUTES) || 2;
        const resendIn = String(now.getTime() + (resendInMinute * 60000));
        if(otpExists) {
            otpExists.code = otpCode;
            otpExists.expiresIn = expiresIn;
            otpExists.resendIn = resendIn
            await otpExists.save()
        } else {
            await this.otpModel.insert({
                code: otpCode,
                expiresIn: expiresIn,
                phone: TARGET_PHONE_NUMBER,
                identifier: otpCode,
                resendIn
            })
        }
        let diff: number = Number(resendIn) - currentTime;
        return {
            phone:TARGET_PHONE_NUMBER,
            resendIn: Math.floor(diff/1000)
        }
    }

    async phoneVerifyService(
        req: Request,
        TARGET_PHONE_NUMBER: string,
        code: string,
        ip: string,
        ua: string,
        method: string
    ) {
        try {
            code = this.decryptCryptoJS(code)
            // const result = await this.phoneService.verify(TARGET_PHONE_NUMBER, code);
            const user = await this.userModel.findOneBy({phone:TARGET_PHONE_NUMBER});
            if(!user) {
                throw new HttpException("Phone Number doesn't exists", HttpStatus.BAD_REQUEST)
            }
            const otp = await this.otpModel.findOneBy({phone: TARGET_PHONE_NUMBER})
            if(!otp) {
                throw new HttpException("Invalid Phone Number", HttpStatus.BAD_REQUEST)
            }
    
            if(otp.code!=code) {
                throw new HttpException("Invalid OTP Code", HttpStatus.BAD_REQUEST)
            }
    
            let currentTime = new Date().getTime();
            let diff: number = Number(otp.expiresIn) - currentTime;
            if(diff<0) {
                // code expired
                throw new HttpException("OTP Code Expired", HttpStatus.BAD_REQUEST)
            }
            user.phone = TARGET_PHONE_NUMBER
            user.isActivated = true
            await user.save()
            await otp.remove()
            await this.removeLimit(TARGET_PHONE_NUMBER, ip);
            const hasNextPage = this.checkHasNextPage(req, "2fa", new UserDto(user))
            if (hasNextPage) return hasNextPage;
            await this.loggingService.logSuccessfulLogin(user, ip, ua, method, true)
            return await this.tokenSession(req, user, ip)
        } catch (error) {
            try {
                // Consume 1 point from limiters on wrong attempt and block if limits reached
                await Promise.all([
                    this.softLoginLimit.consume(this.getUsernameIPkey(TARGET_PHONE_NUMBER, ip)),
                    this.hardLoginLimit.consume(ip)
                ])
            } catch (tlError) {
                if(tlError?.msBeforeNext) {
                    throw new HttpException({"message": "Too Many Requests", msBeforeNext: tlError.msBeforeNext}, 429);
                }
            }
            throw error;
        }
    }
}