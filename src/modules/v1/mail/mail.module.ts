import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailController } from './mail.controller';
import { MailerModule } from '@nestjs-modules/mailer';
import {SES} from 'aws-sdk';

@Module({
  providers: [MailService],
  controllers: [MailController],
  imports: [
    MailerModule.forRootAsync({
      useFactory: () => ({
        transport: {
          SES: new SES({
            region: process.env.AWS_REGION,
            accessKeyId: process.env.AWS_ACCESS_KEY,
            secretAccessKey: process.env.AWS_SECRET_KEY,
          }),
          host: process.env.SMTP_HOST,
          port: Number(process.env.SMTP_PORT),
          secure: process.env.NODE_ENV !== 'development',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD,
          },
        },
      }),
    }),
  ],
  exports: [MailService],
})
export class MailModule {}