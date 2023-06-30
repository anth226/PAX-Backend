import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

export class OTPDto {
  @ApiProperty({ example: '+1XXXXXXXXXX' })
  @IsString()
  phone: string;
}

export class OTPMailDto {
  @ApiProperty({ example: 'admin@example.com' })
  @IsEmail()
  email: string;
}

export class OTPVerifyDto {
  @ApiProperty({ example: '+1XXXXXXXXXX' })
  @IsString()
  phone: string;

  @ApiProperty({ example: '123456' })
  @IsString()
  code: string;
}