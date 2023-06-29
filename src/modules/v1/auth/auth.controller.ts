import { Body, Controller, HttpException, HttpStatus, Ip, Post, Req, Res, Get, Redirect, Param, Put } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { UserEntity } from "../users/entity/user.entity";
import { Repository } from "typeorm";
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from "../users/dto/create-user.dto";
import { ApiTags } from '@nestjs/swagger';
import { ErrorHandle } from "src/exceptions/ErrorHandle";
import { Request } from "express";

@Controller('api/v1/auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    @InjectRepository(UserEntity) private readonly userModel: Repository<UserEntity>,
  ) {}

  @Post('/register')
  async register(
    @Req() req: Request,
    @Body() dto: CreateUserDto,
  ) {
    try {
      const userData = await this.authService.register(dto)
      if(!userData) {
        throw new HttpException("User not found with that email.", HttpStatus.BAD_REQUEST)
      }
      return true
    } catch (error) {
      return ErrorHandle(error) 
    }
  }
  @Post('/check/email')
  async checkEmail(
    @Req() req: Request,
    @Body() dto: CreateUserDto,
  ) {
    try {
      const userData = await this.authService.checkEmail(dto)
      if(!userData) {
        throw new HttpException("User not found with that email.", HttpStatus.BAD_REQUEST)
      }
      return true
    } catch (error) {
      return ErrorHandle(error) 
    }
  }

  @Post('/login')
  async login(
    @Ip() ip: any,
    @Req() req: Request,
    @Body() dto: CreateUserDto,
    @Res({ passthrough: true }) response: any,
  ) {
    try {
      const fingerprint = req.headers['fingerprint'];
      const os = req.headers['sec-ch-ua-platform'];
      const ua = req.headers['user-agent'];
      const userData = await this.authService.login(
        dto,
        ip,
        ua,
        fingerprint,
        os,
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
  async VerifyMail(@Body() dto: any, @Req() req: any, @Ip() ip: any, @Res() res: any) {
    try {
        const userData = await this.authService.verifyOtpMail(
          dto.email,
          dto.code,
          ip,
          req.headers['user-agent'],
          req.headers['fingerprint'],
          req.headers['sec-ch-ua-platform'],
        );
        return userData;
    } catch (error) {
        return ErrorHandle(error)
    }
  }

  @Get('/activate/:link')
  @Redirect(process.env.CLIENT_URL, 302)
  async activate(@Param('link') activationLink: string) {
    try {
      const authLink = await this.authService.activateAccount(activationLink);
      if (authLink.isActivated) {
        return { url: process.env.CLIENT_URL };
      }
    } catch (error) {
      return ErrorHandle(error)
    }
  }

  @Get('/refresh')
  async refreshGet(
    @Ip() ip: any,
    @Req() req: any,
    @Body() dto: any,
    @Res({ passthrough: true }) response: any,
  ) {
    try {
        const os = req.headers['sec-ch-ua-platform'];
        const fingerprint = req.headers['fingerprint'];

        const userData = await this.authService.refreshToken(
        dto.refreshToken,
        ip,
        req.headers['user-agent'],
        os,
        response,
        fingerprint,
        );
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
 resetPassword(@Body() body: any) {
    try {
        return this.authService.resetPassword(body.email);
    } catch (error) {
        return ErrorHandle(error)
    }
  }

 @Post('/change-reset-link')
 changeResetPwd(@Body() body: any) {
    try {
        return this.authService.changeResetPassword(body.email, body.link);
    } catch (error) {
        return ErrorHandle(error)
    }
  }

  // TODO: Still Need to make it
  @Put('/password')
  async passwordUpdate(@Body() body: any) {
    try {
        return this.authService.newResetPassword(body.email, body.password)
    } catch (error) {
        
    }
  }
}