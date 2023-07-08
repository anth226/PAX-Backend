import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class UpdatePasswordDto {
  @ApiProperty({ example: '123456', description: 'Your Current Password' })
  @IsString()
  current_password: string;

  @ApiProperty({ example: '123456', description: 'Your New Password' })
  @IsString()
  new_password: string;

  @ApiProperty({ example: '123456', description: 'Your Mathching Password to new_password' })
  @IsString()
  confirm_password: string;
}
