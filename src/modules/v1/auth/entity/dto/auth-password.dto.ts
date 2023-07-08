import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class AuthPasswordDto {
  @ApiProperty({ example: '123456' })
  @IsString()
  password: string;
}
