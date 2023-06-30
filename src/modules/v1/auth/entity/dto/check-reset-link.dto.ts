import { ApiProperty } from '@nestjs/swagger';

export class CheckResetLinkDto {
  @ApiProperty({ example: 'example@example.com'})
  email: string;

  @ApiProperty({ example: '111', description: "Reset Link Code" })
  reset_code: string;
}