import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches } from 'class-validator';
import { Match } from 'src/custom-decorators/match.decorator';

export class ChangePasswordDto {
  @ApiProperty({ example: '111slldfe', description: "Reset Link Code" })
  @IsString()
  reset_code: string;

  @ApiProperty({ example: '123456', description: "New Password" })
  @IsString()
  password: string;

  @ApiProperty({ example: '123456', description: "Confirmation Password matching to password" })
  @IsString()
  @Match("password")
  confirm_password: string;
}