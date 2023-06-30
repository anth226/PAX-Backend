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
    // private phoneService: PhoneService,
    // private readonly client: TwilioClient,
    private connection: Connection, // TypeORM transactions.
  ) {}

    async register(userData:any) {
        const user = await this.userModel.findOneBy({email: userData.email});
        if (user) {
            throw new BadRequestException('email already exists.');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(userData.password, salt);
        await this.userModel.insert({
            email:userData.email,
            password: hashPassword,
            isActivated: true
        })
        return userData;
    }

    async checkEmail(userData:any) {
        try {
            return await this.getUserByEmail(userData.email)
        } catch (error) {
            throw new HttpException(error.message, 500)
        }
    }

    async login(userData: any, ip: string, ua: any, fingerprint: any, os: any) {
        try {
            const user = await this.validateUser(userData);
            if (user.banned) {
                throw new UnauthorizedException({
                    message: `You are banned: ${user.banReason}`,
                });
            }
            const userDataAndTokens = await this.tokenSession(user, ip, ua, fingerprint, os);
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

    async tokenSession(userData: any, ip: string, ua: any, fingerprint?: any, os?: any) {
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
        await this.saveToken(userData.id, tokens.refreshToken, ip, ua, os, fingerprint);
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
        ua: any,
        os?: any,
        fingerprint?: any,
    ) {
        // if (!fingerprint) {
        //     throw new HttpException(`Missing browser fingerprint!`, HttpStatus.BAD_REQUEST);
        // }
        const hasToken = await this.tokenModel.findOneBy({ user: userId, fingerprint });
        // create a token from scratch for a new user or after deleting an old token
        if (!hasToken) {
            const createdToken = this.tokenModel.create({
                user: userId,
                refreshToken,
                ip,
                ua,
                os,
                fingerprint,
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

    async verifyOtpMail(
        email: string,
        code: string,
        ip: string,
        ua: string,
        fingerprint: string,
        os: string,
    ) {
        let data = await this.otpModel.findOneBy({ email, code, fingerprint });
        let response: any;
        if (data) {
            let currentTime = new Date().getTime();
            let diff: any = Number(data.expiresIn) - currentTime;
            if (diff < 0) {
                throw new HttpException("Code Expired", HttpStatus.BAD_REQUEST)
            } else {
                const findUser = await this.getUserByEmail(email);
                if(!findUser) {
                    throw new HttpException("Invalid Email", HttpStatus.BAD_REQUEST)
                }
                const userDataAndTokens = await this.tokenSession(
                    findUser,
                    ip,
                    ua,
                    fingerprint,
                    os,
                );
                return userDataAndTokens;
            }
        }
        throw new HttpException("Invalid OTP Code", HttpStatus.BAD_REQUEST)
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
            throw new BadRequestException('Invalid email');
        }
        var salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password, salt);
        user.password = hashPassword;
        await user.save();
        return;
    }

    async refreshToken(
        refreshtoken: string,
        ip: string,
        ua: any,
        os: any,
        res: any,
        fingerprint: any,
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
        const userDataAndTokens = await this.tokenSession(user, ip, ua, fingerprint, os);
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

    // async sendPhone(TARGET_PHONE_NUMBER: string) {
    //     return await this.phoneService.sendPhoneSMS(TARGET_PHONE_NUMBER);
    // }

    // async phoneVerifyService(
    //     TARGET_PHONE_NUMBER: string,
    //     code: string,
    //     ip: string,
    //     ua: string,
    //     fingerprint: string,
    //     os: string,
    // ) {
    //     try {
    //         const result = await this.phoneService.verify(TARGET_PHONE_NUMBER, code);
    //         const hasPhone = await this.userModel.findOneBy({phone:TARGET_PHONE_NUMBER});
    //         let createUser: UserEntity;
    //         if (result.valid) {
    //             if (!hasPhone) {
    //                 // user creation
    //                 createUser = new UserEntity();
    //                 createUser.phone = TARGET_PHONE_NUMBER;
    //                 createUser.isActivated = true;
    //                 await createUser.save();
    //             }
    //             const userDataAndTokens = await this.tokenSession(
    //                 hasPhone ?? createUser,
    //                 ip,
    //                 ua,
    //                 fingerprint,
    //                 os,
    //             );
    //             return {
    //                 message: 'User is Verified!!',
    //                 status: result.status,
    //                 valid: result.valid,
    //                 dateCreated: result.dateCreated,
    //                 dateUpdated: result.dateUpdated,
    //                 ...userDataAndTokens,
    //             };
    //         }
    //         throw new HttpException("Invalid Code", HttpStatus.BAD_REQUEST)
    //     } catch (error) {
    //         throw new UnauthorizedException({
    //             message: 'Server Error',
    //         });
    //     }
    // }
}