import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as winston from 'winston';
import { Repository } from 'typeorm';
import { LoginLogEntity } from './entity/login-logging.entity';
import { UserEntity } from '../users/entity/user.entity';

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'login-logs.log' }),
  ],
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
});

@Injectable()
export class LoggingService {
  constructor(
    @InjectRepository(LoginLogEntity) private readonly loginLogModel: Repository<LoginLogEntity>,
  ) {}

  async logSuccessfulLogin(
    user: UserEntity,
    ip: string,
    userAgent: string,
    loginMethod: string,
    otpStatus: boolean = true,
    location: string = '',
  ): Promise<void> {
    const loggingMethod = process.env.LOGGING_METHOD || 'db';
    if (loggingMethod == 'file') {
      logger.info({
        userId: user.id,
        ip,
        userAgent,
        loginMethod,
        otpStatus,
        location,
      });
      return;
    }
    await this.loginLogModel.insert({
      user,
      ip,
      userAgent,
      loginMethod,
      otpStatus,
      location,
    });
  }
}
