import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';
import { Match } from 'src/custom-decorators/match.decorator';

export class UpdatePasswordDto {
  @ApiProperty({ example: '123456', description: "Your Current Password" })
  @IsString()
  current_password: string;

  @ApiProperty({ example: '123456', description: "Your New Password" })
  @IsString()
  new_password: string;

  @ApiProperty({ example: '123456', description: "Your Mathching Password to new_password" })
  @IsString()
  @Match("new_password")
  confirm_password: string;

}