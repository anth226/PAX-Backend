import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNumber, IsString } from 'class-validator';

export class OTPDto {
  @ApiProperty({ example: 1 })
  @IsNumber()
  methodId: number;
}

export class OTPPhoneDto {
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
  @ApiProperty({ example: 1 })
  @IsNumber()
  methodId: number;

  @ApiProperty({ example: '123456' })
  @IsString()
  code: string;
}
