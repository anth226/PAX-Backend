import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

export class CheckResetLinkDto {
  @ApiProperty({ example: 'example@example.com'})
  @IsEmail()
  email: string;

  @ApiProperty({ example: '111', description: "Reset Link Code" })
  @IsString()
  reset_code: string;
}