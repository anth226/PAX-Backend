import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class VerifyMailDto {
  @ApiProperty({
    description: 'The email address to be verified',
    example: 'example@example.com',
  })
  @IsString()
  email: string;

  @ApiProperty({
    description: 'The verification code',
    example: '123456',
  })
  @IsString()
  code: string;
}
