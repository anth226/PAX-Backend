import { ApiProperty } from '@nestjs/swagger';
import { IsEmail } from 'class-validator';

export class AuthEmailDto {
  @ApiProperty({ example: 'test1@example.com' })
  @IsEmail()
  email: string;
}