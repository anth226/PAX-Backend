import {
  Body,
  Controller,
  HttpException,
  HttpStatus,
  Ip,
  Post,
  Req,
  Res,
  Get,
  Headers,
  Redirect,
  Param,
  Put,
  HttpCode,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { ApiResponse } from '@nestjs/swagger';
import { ErrorHandle } from 'src/exceptions/ErrorHandle';
import { Request, Response } from 'express';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { PreAuthGuard } from 'src/guards/pre-auth.guard';
import { I18nService } from 'nestjs-i18n';
import { I18nTranslations } from 'src/generated/i18n.generated';
import { AuthService } from './auth.service';
import { UserEntity } from '../users/entity/user.entity';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { AuthEmailDto } from './entity/dto/auth-email.dto';
import { LoginResponseDto } from './entity/dto/login-response.dto';
import { VerifyMailDto } from './entity/dto/verify-mail.dto';
import { RefreshTokenDto } from './entity/dto/refresh-token.dto';
import { CheckResetLinkDto } from './entity/dto/check-reset-link.dto';
import { ChangePasswordDto } from './entity/dto/change-password.dto';
import { OTPVerifyDto, OTPMailDto, OTPPhoneDto, OTPDto } from './entity/dto/otp.dto';

import { UpdatePasswordDto } from './entity/dto/update-password.dto';
import { IExpressUser } from 'src/@types/user';

const CryptoJS = require('crypto-js');

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly i18n: I18nService<I18nTranslations>,
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
  ) {}

  @Post('/register')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: CreateUserDto })
  async register(@Req() req: Request, @Body() dto: CreateUserDto) {
    try {
      const userData = await this.authService.register(dto);
      return userData;
    } catch (error) {
      return ErrorHandle(error);
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
      await this.authService.limitLogin(dto.email, ip);
      const userData = await this.authService.checkEmail(dto);
      if (!userData) {
        throw new HttpException(
          this.i18n.translate('common.auth.invalid_user'),
          HttpStatus.BAD_REQUEST,
        );
      }
      res.status(200).json();
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }

  @Post('/login')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async login(
    @Ip() ip: any,
    @Body() dto: CreateUserDto,
    @Headers() headers: Record<string, string>,
    @Res() res: Response,
    @Req() req: Request,
  ) {
    try {
      await this.authService.limitLogin(dto.email, ip);
      const ua = headers['user-agent'];
      const { method } = req;
      const userData = await this.authService.login(req, dto, ip, ua, method);
      res.status(200).json(userData);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }


  @Post("/send/otp")
  @UseGuards(PreAuthGuard)
  @HttpCode(HttpStatus.OK)
  async sendOtpCode(
    @Body() dto: OTPDto,
    @Req() req: Request,
    @Res() res: Response,
    @Ip() ip: any
  ) {
    try {
      const currentUser = req.user as IExpressUser
      const otpMethod = await this.authService.getTwoFactorMethodById(dto.methodId, currentUser.id)
      await this.authService.limitLogin(otpMethod.methodDetail, ip);
      let response = null;
      if(otpMethod.methodType==="email") {
        response = await this.authService.generateOtpMail(otpMethod.methodDetail);
      } else {
        response = await this.authService.sendOtpPhone(otpMethod.methodDetail);
      }
      res.status(200).json(response);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }

  @Post('/send/otp/mail')
  @UseGuards(PreAuthGuard)
  @HttpCode(HttpStatus.OK)
  async sendOtpMail(@Body() dto: OTPMailDto, @Res() res: Response, @Ip() ip: any) {
    try {
      await this.authService.limitLogin(dto.email, ip);
      const response = await this.authService.generateOtpMail(dto.email);
      res.status(200).json(response);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }

  @Post('/verify/mail')
  @UseGuards(PreAuthGuard)
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async VerifyMail(
    @Body() dto: OTPVerifyDto,
    @Req() req: Request,
    @Ip() ip: any,
    @Res() res: Response,
    @Headers() headers: Record<string, string>,
  ) {
    try {
      const currentUser = req.user as IExpressUser
      await this.authService.limitLogin(currentUser.email, ip);

      const otpMethod = await this.authService.getTwoFactorMethodById(dto.methodId, currentUser.id)
      const ua = headers['user-agent'];
      const { method } = req;
      const userData = await this.authService.verifyOtpMail(
        req,
        currentUser.email,
        dto.code,
        otpMethod.methodDetail,
        ip,
        ua,
        method,
      );
      return res.status(200).json(userData);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
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

  // @Get('/refresh')
  // @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  // async refreshGet(
  //   @Ip() ip: any,
  //   @Req() req: Request,
  //   @Body() dto: RefreshTokenDto,
  // ) {
  //   try {
  //       const userData = await this.authService.refreshToken(req, dto.refreshToken, ip);
  //       return userData;
  //   } catch (error) {
  //     return ErrorHandle(error)
  //   }
  // }

  @Post('/send/otp/phone')
  @UseGuards(PreAuthGuard)
  @HttpCode(HttpStatus.OK)
  async phoneSendOne(@Body() dto: OTPPhoneDto, @Res() res: Response, @Ip() ip: any) {
    try {
      await this.authService.limitLogin(dto.phone, ip);
      const response = await this.authService.sendOtpPhone(dto.phone);
      res.status(200).json(response);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }

  @Post('/verify/otp/phone')
  @UseGuards(PreAuthGuard)
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async verifyOtpPhone(
    @Req() req: Request,
    @Body() dto: OTPVerifyDto,
    @Ip() ip: any,
    @Res() res: Response,
    @Headers() headers: Record<string, string>,
  ) {
    try {
      const currentUser = req.user as IExpressUser
      await this.authService.limitLogin(currentUser.email, ip);

      const otpMethod = await this.authService.getTwoFactorMethodById(dto.methodId, currentUser.id)
      const ua = headers['user-agent'];
      const { method } = req;
      const userData = await this.authService.phoneVerifyService(
        req,
        currentUser.email,
        dto.code,
        otpMethod.methodDetail,
        ip,
        ua,
        method,
      );
      res.status(200).json(userData);
    } catch (error) {
      if (error?.response?.msBeforeNext) {
        res.set('Retry-After', String(Math.round(error?.response?.msBeforeNext / 1000) || 1));
        return res
          .status(429)
          .json({ message: this.i18n.translate('common.auth.too_many_requests'), statusCode: 429 });
      }
      return res.status(500).json({ message: error.message, statusCode: 500 });
    }
  }

  @Post('/reset-password')
  @HttpCode(HttpStatus.OK)
  resetPassword(@Body() body: AuthEmailDto) {
    try {
      return this.authService.resetPassword(body.email);
    } catch (error) {
      return ErrorHandle(error);
    }
  }

  @Post('/check-reset-link')
  @HttpCode(HttpStatus.OK)
  checkResetPwd(@Body() body: CheckResetLinkDto) {
    try {
      return this.authService.checkResetPassword(body.reset_code);
    } catch (error) {
      return ErrorHandle(error);
    }
  }

  @Put('/require/password-reset')
  @UseGuards(PreAuthGuard)
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async requirePassReset(
    @Req() req: Request,
    @Body() dto: UpdatePasswordDto,
    @Ip() ip: any,
    @Headers() headers: Record<string, string>,
  ) {
    try {
      const ua = headers['user-agent'];
      const { method } = req;
      return await this.authService.requirePassReset(req, req.user, dto, ip, ua, method);
    } catch (error) {
      return ErrorHandle(error);
    }
  }

  @Put('/password')
  @HttpCode(HttpStatus.OK)
  async passwordUpdate(@Body() body: ChangePasswordDto) {
    try {
      return await this.authService.newResetPassword(
        body.password,
        body.confirm_password,
        body.reset_code,
      );
    } catch (error) {
      return ErrorHandle(error);
    }
  }
}
