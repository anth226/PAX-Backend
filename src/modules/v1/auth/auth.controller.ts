import { Body, Controller, HttpException, HttpStatus, Ip, Post, Req, Res, Get, Redirect, Param, Put, HttpCode } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { UserEntity } from "../users/entity/user.entity";
import { Repository } from "typeorm";
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from "../users/dto/create-user.dto";
import { ApiResponse, ApiTags } from '@nestjs/swagger';
import { ErrorHandle } from "src/exceptions/ErrorHandle";
import { Request } from "express";
import { AuthEmailDto } from "./entity/dto/auth-email.dto";
import { LoginResponseDto } from "./entity/dto/login-response.dto";
import { VerifyMailDto } from "./entity/dto/verify-mail.dto";
import { RefreshTokenDto } from "./entity/dto/refresh-token.dto";
import { CheckResetLinkDto } from "./entity/dto/check-reset-link.dto";
import { ChangePasswordDto } from "./entity/dto/change-password.dto";
import { UserDto } from "../users/dto/user.dto";

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
  ) {
    try {
      const userData = await this.authService.login(
        dto,
        ip
      );
      if (userData.user.isActivated === false) {
        throw new HttpException("User is not activated.", HttpStatus.BAD_REQUEST)
      }
      return userData;
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  @Post('/verify/mail')
  @ApiResponse({ status: HttpStatus.OK, isArray: false, type: LoginResponseDto })
  async VerifyMail(@Body() dto: VerifyMailDto, @Req() req: any, @Ip() ip: any, @Res() res: any) {
    try {
        const userData = await this.authService.verifyOtpMail(
          dto.email,
          dto.code,
          ip,
        );
        return userData;
    } catch (error) {
        return ErrorHandle(error)
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
    @Req() req: any,
    @Body() dto: RefreshTokenDto,
    @Res({ passthrough: true }) response: any,
  ) {
    try {
        const userData = await this.authService.refreshToken(dto.refreshToken, ip);
        return userData;
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  // @Get('/verify/phone')
  // async phoneVerify(@Ip() ip: string, @Req() req: any, @Res() res: any) {
  //   try {
  //     const verifyResult = await this.authService.phoneVerifyService(
  //       req.query.phonenumber,
  //       req.query.code,
  //       ip,
  //       req.headers['user-agent'],
  //       req.headers['fingerprint'],
  //       req.headers['sec-ch-ua-platform'],
  //     );
  //     return verifyResult
  //   } catch (error) {
  //     return ErrorHandle(error)
  //   }
  // }

  // @Post('/send_one/phone')
  // async phoneSendOne(@Req() req: any, @Res() res: any) {
  //   try {
  //     const sendSMS = await this.authService.sendPhone(req.body.number);
  //     return sendSMS;
  //   } catch (error) {
  //     return ErrorHandle(error)
  //   }
  // }

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
        return this.authService.checkResetPassword(body.email, body.reset_code);
    } catch (error) {
        return ErrorHandle(error)
    }
  }

  // TODO: Still Need to make it
  @Put('/password')
  @HttpCode(HttpStatus.OK)
  async passwordUpdate(@Body() body: ChangePasswordDto) {
    try {
        return this.authService.newResetPassword(body.email, body.password, body.reset_code)
    } catch (error) {
        return ErrorHandle(error)
    }
  }
}