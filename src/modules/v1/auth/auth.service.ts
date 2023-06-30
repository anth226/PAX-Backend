import { HttpStatus, Injectable, UnauthorizedException, HttpException, MethodNotAllowedException, BadRequestException } from '@nestjs/common';
import {InjectRepository} from '@nestjs/typeorm';
import { Connection, Repository } from 'typeorm';
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


@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
    @InjectRepository(UserRoleEntity) private readonly userRoleModel: Repository<UserRoleEntity>,
    @InjectRepository(OTPEntity) private readonly otpModel: Repository<OTPEntity>,
    @InjectRepository(RefreshTokenSessionsEntity)
    private readonly tokenModel: Repository<RefreshTokenSessionsEntity>,
    // private roleService: RoleService,
    private jwtService: JwtService,
    private mailService: MailService,
    private phoneService: PhoneService,
    // private readonly client: TwilioClient,
    private connection: Connection, // TypeORM transactions.
  ) {}

    async register(userData:CreateUserDto) {
        const user = await this.userModel.findOneBy({email: userData.email});
        if (user) {
            throw new BadRequestException('email already exists.');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(userData.password, salt);
        await this.userModel.insert({
            email:userData.email,
            password: hashPassword,
            isActivated: true,
            phone: userData.phone ?? null
        })
        const link = `${process.env.CLIENT_URL}/signin/activate`
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

    async login(userData: any, ip: string) {
        try {
            const user = await this.validateUser(userData);
            if (user.banned) {
                throw new UnauthorizedException({
                    message: `You are banned: ${user.banReason}`,
                });
            }
            const userDataAndTokens = await this.tokenSession(user, ip);
            return userDataAndTokens;
        } catch (error) {
            throw new HttpException(error.message, 500)
        }
    }

    async validateUser(userData: any): Promise<any> {
        try {
            const user = await this.getUserByEmail(userData.email);
            if (!user) {
                throw new HttpException({
                    message: `User with email ${userData.email} not found`,
                }, HttpStatus.BAD_REQUEST);
            }
            const isPasswordEquals = await bcrypt.compare(userData.password, user.password);
            if (!isPasswordEquals) throw new HttpException({ message: `Incorrect Password` }, HttpStatus.BAD_REQUEST);
            const { password, ...result } = user;
            return result;
        } catch (error) {
            throw new Error(error)
        }
    }

    async tokenSession(userData: any, ip: string) {
        if (!userData) {
            throw new UnauthorizedException({
                message: 'The user with the given ID is not in the database',
            });
        }
        // pulling out roles for results
        if (!userData.roles) {
            const userRoles = await this.connection.getRepository(UserRoleEntity).createQueryBuilder('user-roles').innerJoinAndSelect('user-roles.role', 'role').where('user-roles.userId = :id', {id: userData.id}).getMany()
            userData.roles = userRoles.map(userRoles => userRoles.role);
        }
        const userDto = new UserDto(userData);
        const tokens = await this.generateToken({ ...userDto });
        await this.saveToken(userData.id, tokens.refreshToken, ip);
        return {
            statusCode: HttpStatus.OK,
            message: 'User information',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken, // refresh token only for mobile app
            user: userDto,
        };
    }


    async getUserByEmail(email: string) {
        const user = await this.userModel.findOneBy({ email });
        return user;
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

    async saveToken(
        userId: any,
        refreshToken: string,
        ip: string,
    ) {
        // if (!fingerprint) {
        //     throw new HttpException(`Missing browser fingerprint!`, HttpStatus.BAD_REQUEST);
        // }
        const hasToken = await this.tokenModel.findOneBy({ user: userId });
        // create a token from scratch for a new user or after deleting an old token
        if (!hasToken) {
            const createdToken = this.tokenModel.create({
                user: userId,
                refreshToken,
                ip,
                expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
            });
            return await this.tokenModel.save(createdToken);
        }
        hasToken.refreshToken = refreshToken;
        const tokenData = await this.tokenModel.save(hasToken);
        return tokenData;
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
        const message = `Your OTP Code: ${otpCode}`
        const now = new Date();
        const expirationInMinute = Number(process.env.OTP_EXPIRATION) ?? 30;
        const expiresIn = String(now.getTime() + (expirationInMinute * 60000));

        const otpExists = await this.otpModel.findOneBy({email})
        if(otpExists) {
            let currentTime = new Date().getTime();
            let diff: number = Number(otpExists.expiresIn) - currentTime;
            if(diff>0) {
                throw new HttpException({
                    message: `You've already generated OTP Code. Please try again afte ${this.formatTimeDuration(diff)}`,
                }, HttpStatus.BAD_REQUEST);
            }
        }
        await this.mailService.sendMailCode(email, otpCode);
        if(otpExists) {
            otpExists.code = otpCode;
            otpExists.expiresIn = expiresIn;
            await otpExists.save()
        } else {
            await this.otpModel.insert({
                code: otpCode,
                expiresIn: expiresIn,
                email: email
            })
        }
        return {
            email:email,
            expiresIn: expiresIn,
        }
    }

    async verifyOtpMail(
        email: string,
        code: string,
        ip: string,
    ) {

        const user = await this.userModel.findOneBy({email});
        if(!user) {
            throw new HttpException("Email doesn't exists", HttpStatus.BAD_REQUEST)
        }
        const otp = await this.otpModel.findOneBy({email})
        if(!otp) {
            throw new HttpException("Invalid Email", HttpStatus.BAD_REQUEST)
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
        return await this.tokenSession(user, ip)
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
        user.resetLink = linkReset
        await user.save()
        return;
    }

    async checkResetPassword(email: any, resetLink: any) {
        const user = await this.getUserByEmail(email);
        if (!user) {
            throw new BadRequestException('Invalid email');
        }
        if (resetLink && user.resetLink !== resetLink) {
            throw new BadRequestException('Invalid Reset Link');
        }
        return;
    }

    async newResetPassword(email: string, password: string, resetLink: string) {
        const user = await this.userModel.findOneBy({email, resetLink});
        if (!user) {
            throw new BadRequestException('Invalid email or code');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        user.password = hashPassword;
        user.resetLink = null;
        await user.save();
        return;
    }

    async refreshToken(
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
        const userDataAndTokens = await this.tokenSession(user, ip);
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


    async sendOtpPhone(TARGET_PHONE_NUMBER: string) {
        const user = await this.userModel.findOneBy({phone:TARGET_PHONE_NUMBER})
        if(!user) {
            throw new HttpException({
                message: `Invalid Email`,
            }, HttpStatus.BAD_REQUEST);
        }

        const otpCode: string = this.generateOTP(6)
        const message = `Your OTP Code: ${otpCode}`
        const now = new Date();
        const expirationInMinute = Number(process.env.OTP_EXPIRATION) ?? 30;
        const expiresIn = String(now.getTime() + (expirationInMinute * 60000));

        const otpExists = await this.otpModel.findOneBy({phone:TARGET_PHONE_NUMBER})
        if(otpExists) {
            let currentTime = new Date().getTime();
            let diff: number = Number(otpExists.expiresIn) - currentTime;
            if(diff>0) {
                throw new HttpException({
                    message: `You've already generated OTP Code. Please try again afte ${this.formatTimeDuration(diff)}`,
                }, HttpStatus.BAD_REQUEST);
            }
        }
        await this.phoneService.sendPhoneSMS(TARGET_PHONE_NUMBER, message);
        if(otpExists) {
            otpExists.code = otpCode;
            otpExists.expiresIn = expiresIn;
            await otpExists.save()
        } else {
            await this.otpModel.insert({
                code: otpCode,
                expiresIn: expiresIn,
                phone: TARGET_PHONE_NUMBER
            })
        }
        return {
            phone:TARGET_PHONE_NUMBER,
            expiresIn: expiresIn,
        }
    }

    async phoneVerifyService(
        TARGET_PHONE_NUMBER: string,
        code: string,
        ip: string
    ) {
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
        return await this.tokenSession(user, ip)
    }
}