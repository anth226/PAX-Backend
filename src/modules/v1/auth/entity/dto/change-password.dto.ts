import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty({ example: 'example@example.com'})
  email: string;

  @ApiProperty({ example: '111slldfe', description: "Reset Link Code" })
  reset_code: string;

  @ApiProperty({ example: '123456', description: "New Password" })
  password: string;

  @ApiProperty({ example: '123456', description: "Confirmation Password matching to password" })
  confirm_password: string;
}