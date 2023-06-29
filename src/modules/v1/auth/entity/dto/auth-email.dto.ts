import { ApiProperty } from '@nestjs/swagger';

export class AuthEmailDto {
  @ApiProperty({ example: 'test1@example.com' })
  email: string;
}