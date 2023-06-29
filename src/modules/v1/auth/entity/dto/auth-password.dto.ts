import { ApiProperty } from '@nestjs/swagger';

export class AuthPasswordDto {
  @ApiProperty({ example: '123456' })
  password: string;
}