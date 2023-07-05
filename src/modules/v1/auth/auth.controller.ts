import { Body, Controller, HttpException, HttpStatus, Ip, Post, Req, Res, Get, Headers, Redirect, Param, Put, HttpCode, UseGuards, BadRequestException } from "@nestjs/common";
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
import { UpdatePasswordDto } from "./entity/dto/update-password.dto";
import { PreAuthGuard } from "src/guards/pre-auth.guard";
var CryptoJS = require("crypto-js");

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
    @Res() res: Response,
    @Ip() ip: any,
  ) {
    try {
      await this.authService.limitLogin(dto.email, ip)
      const userData = await this.authService.checkEmail(dto)
      if(!userData) {
        throw new HttpException("User not found with that email.", HttpStatus.BAD_REQUEST)
      }
      res.status(200).json()
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
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
  async sendOtpMail(
    @Body() dto: OTPMailDto,
    @Res() res: Response,
    @Ip() ip: any,
    ) {
    try {
      await this.authService.limitLogin(dto.email, ip)
      const response = await this.authService.generateOtpMail(dto.email);
      res.status(200).json(response)
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
    }
  }

  @Post('/verify/mail')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async VerifyMail(
    @Body() dto: VerifyMailDto,
    @Req() req: Request,
    @Ip() ip: any,
    @Res() res: Response,
    @Headers() headers: Record<string, string>
    ) {
    try {
      await this.authService.limitLogin(dto.email, ip)
      const ua = headers['user-agent'];
      const method = req.method
      const userData = await this.authService.verifyOtpMail(
        req,
        dto.email,
        dto.code,
        ip,
        ua,
        method
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
  async phoneSendOne(
    @Body() dto: OTPDto,
    @Res() res: Response,
    @Ip() ip: any,
    ) {
    try {
      await this.authService.limitLogin(dto.phone, ip)
      const response = await this.authService.sendOtpPhone(dto.phone);
      res.status(200).json(response)
    } catch (error) {
      if(error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res.status(429).json({"message": "Too Many Requests", statusCode: 429});
      }
      return res.status(500).json({"message": error.message, statusCode: 500});
    }
  }

  @Post('/verify/otp/phone')
  @ApiResponse({status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async verifyOtpPhone(
    @Req() req: Request,
    @Body() dto: OTPVerifyDto,
    @Ip() ip: any,
    @Res() res: Response,
    @Headers() headers: Record <string, string>
    ) {
    try {
      await this.authService.limitLogin(dto.phone, ip)
      const ua = headers['user-agent'];
      const method = req.method
      const userData = await this.authService.phoneVerifyService(req, dto.phone, dto.code, ip, ua, method);
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

  @Post('/require/password-reset')
  @UseGuards(PreAuthGuard)
  @ApiResponse({status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async requirePassReset(
    @Req() req: Request,
    @Body() dto: UpdatePasswordDto,
    @Ip() ip: any,
    @Headers() headers: Record <string, string>
    ) {
      try {
        const ua = headers['user-agent'];
        const method = req.method
        return this.authService.requirePassReset(req, req.user, dto, ip, ua, method);
      } catch (error) {
        return ErrorHandle(error)
      }
    }



  @Put('/password')
  @HttpCode(HttpStatus.OK)
  async passwordUpdate(@Body() body: ChangePasswordDto) {
    try {
        return this.authService.newResetPassword(body.password, body.confirm_password, body.reset_code)
    } catch (error) {
        return ErrorHandle(error)
    }
  }
}