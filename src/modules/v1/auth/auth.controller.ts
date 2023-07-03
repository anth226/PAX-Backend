import { Body, Controller, HttpException, HttpStatus, Ip, Post, Req, Res, Get, Headers, Redirect, Param, Put, HttpCode, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { UserEntity } from "../users/entity/user.entity";
import { Repository } from "typeorm";
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from "../users/dto/create-user.dto";
import { ApiResponse } from '@nestjs/swagger';
import { ErrorHandle } from "src/exceptions/ErrorHandle";
import { Request } from "express";
import { AuthEmailDto } from "./entity/dto/auth-email.dto";
import { LoginResponseDto } from "./entity/dto/login-response.dto";
import { VerifyMailDto } from "./entity/dto/verify-mail.dto";
import { RefreshTokenDto } from "./entity/dto/refresh-token.dto";
import { CheckResetLinkDto } from "./entity/dto/check-reset-link.dto";
import { ChangePasswordDto } from "./entity/dto/change-password.dto";
import { OTPDto, OTPVerifyDto, OTPMailDto } from "./entity/dto/otp.dto";
import { JwtAuthGuard } from "src/guards/jwt-auth.guard";
import {Response} from 'express'

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
  ) {}

  @Post('/register')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: CreateUserDto })
  async register(
    @Req() req: Request,
    @Body() dto: CreateUserDto,
  ) {
    try {
      const userData = await this.authService.register(dto)
      if(!userData) {
        throw new HttpException("User not found with that email.", HttpStatus.BAD_REQUEST)
      }
      return userData
    } catch (error) {
      return ErrorHandle(error) 
    }
  }


  @Post('/check/email')
  @HttpCode(HttpStatus.OK)
  async checkEmail(
    @Req() req: Request,
    @Body() dto: AuthEmailDto,
  ) {
    try {
      const userData = await this.authService.checkEmail(dto)
      if(!userData) {
        throw new HttpException("User not found with that email.", HttpStatus.BAD_REQUEST)
      }
      return;
    } catch (error) {
      return ErrorHandle(error) 
    }
  }

  @Post('/login')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async login(
    @Ip() ip: any,
    @Body() dto: CreateUserDto,
    @Headers() headers: Record<string, string>,
    @Res() res: Response,
    @Req() req: Request
  ) {
    try {
      await this.authService.limitLogin(dto.email, ip)
      const ua = headers['user-agent'];
      const method = req.method
      const userData = await this.authService.login(
        req,
        dto,
        ip,
        ua,
        method
      );
      res.status(200).json(userData)
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
    }
  }

  @Post('/send/otp/mail')
  @HttpCode(HttpStatus.OK)
  async sendOtpMail(@Body() dto: OTPMailDto) {
    try {
      await this.authService.generateOtpMail(dto.email);
      return;
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  @Post('/verify/mail')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async VerifyMail(
    @Body() dto: VerifyMailDto,
    @Req() req: Request,
    @Ip() ip: any,
    @Res() res: Response
    ) {
    try {
      await this.authService.limitLogin(dto.email, ip)
      const userData = await this.authService.verifyOtpMail(
        req,
        dto.email,
        dto.code,
        ip,
      );
      return res.status(200).json(userData)
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
    }
  }

  // @Get('/activate/:link')
  // @Redirect(process.env.CLIENT_URL, 302)
  // async activate(@Param('link') activationLink: string) {
  //   try {
  //     const authLink = await this.authService.activateAccount(activationLink);
  //     if (authLink.isActivated) {
  //       return { url: process.env.CLIENT_URL };
  //     }
  //   } catch (error) {
  //     return ErrorHandle(error)
  //   }
  // }

  @Get('/refresh')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async refreshGet(
    @Ip() ip: any,
    @Req() req: Request,
    @Body() dto: RefreshTokenDto,
  ) {
    try {
        const userData = await this.authService.refreshToken(req, dto.refreshToken, ip);
        return userData;
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  @Post('/send/otp/phone')
  @HttpCode(HttpStatus.OK)
  async phoneSendOne(@Body() dto: OTPDto) {
    try {
      await this.authService.sendOtpPhone(dto.phone);
      return;
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  @Post('/verify/otp/phone')
  @ApiResponse({status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async verifyOtpPhone(
    @Req() req: Request,
    @Body() dto: OTPVerifyDto,
    @Ip() ip: any,
    @Res() res: Response
    ) {
    try {
      await this.authService.limitLogin(dto.phone, ip)
      const userData = await this.authService.phoneVerifyService(req, dto.phone, dto.code, ip);
      res.status(200).json(userData)
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
    }
  }

 @Post('/reset-password')
 @HttpCode(HttpStatus.OK)
 resetPassword(@Body() body: AuthEmailDto) {
    try {
        return this.authService.resetPassword(body.email);
    } catch (error) {
        return ErrorHandle(error)
    }
  }

 @Post('/check-reset-link')
 @HttpCode(HttpStatus.OK)
 checkResetPwd(@Body() body: CheckResetLinkDto) {
    try {
        return this.authService.checkResetPassword(body.reset_code);
    } catch (error) {
        return ErrorHandle(error)
    }
  }

  // TODO: Still Need to make it
  @Put('/password')
  @HttpCode(HttpStatus.OK)
  async passwordUpdate(@Body() body: ChangePasswordDto) {
    try {
        return this.authService.newResetPassword(body.password, body.reset_code)
    } catch (error) {
        return ErrorHandle(error)
    }
  }
}