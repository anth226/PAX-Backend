import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsString, IsNumber, IsOptional, IsDate } from 'class-validator';

export class UserDto {
  @ApiProperty({
    description: 'The unique identifier of the user',
    example: 1,
  })
  @IsNumber()
  id: number;

  @ApiProperty({
    description: 'The ID of the company the user belongs to',
    example: 1,
    required: false,
  })
  @IsOptional()
  @IsNumber()
  companyID: number;

  @ApiProperty({
    description: 'The ID of the organization the user belongs to',
    example: 1,
    required: false,
  })
  @IsOptional()
  @IsNumber()
  organizationID: number;

  @ApiProperty({
    description: 'Flag indicating if the user has an individual account',
    example: true,
  })
  @IsBoolean()
  individualAccount: boolean;

  @ApiProperty({
    description: 'Flag indicating if the user is banned',
    example: false,
  })
  @IsBoolean()
  banned: boolean;

  @ApiProperty({
    description: 'Flag indicating if the user is activated',
    example: true,
  })
  @IsBoolean()
  isActivated: boolean;

  @ApiProperty({
    description: 'Flag indicating if the user needs to reset the password',
    example: true,
  })
  @IsBoolean()
  requirePassReset: boolean;

  @ApiProperty({
    description: 'Flag indicating if the user has accepted latest TOS',
    example: true,
  })
  @IsBoolean()
  hasAcceptedLatestTOS: boolean;

  @ApiProperty({
    description: 'Flag indicating if the user has enabled 2fa',
    example: true,
  })
  @IsBoolean()
  isTwoFactorAuthenticationEnabled: boolean;

  @ApiProperty({
    description: 'The email address of the user',
    example: 'example@example.com',
  })
  @IsString()
  email: string;

  @ApiProperty({
    description: 'The rescue email address of the user',
    example: 'rescue@example.com',
    required: false,
  })
  @IsOptional()
  @IsString()
  rescueEmail: string;

  @ApiProperty({
    description: 'The preferred name of the user',
    example: 'John',
  })
  @IsString()
  namePreferred: string;

  @ApiProperty({
    description: 'Phone Number',
    example: '+1XXXXXXXXXX',
  })
  @IsString()
  phone: string;

  @ApiProperty({
    description: "The prefix of the user's name",
    example: 'Mr.',
  })
  @IsString()
  namePrefix: string;

  @ApiProperty({
    description: 'The first name of the user',
    example: 'John',
  })
  @IsString()
  nameFirst: string;

  @ApiProperty({
    description: 'The middle name of the user',
    example: 'Doe',
  })
  @IsString()
  nameMiddle: string;

  @ApiProperty({
    description: 'The last name of the user',
    example: 'Smith',
  })
  @IsString()
  nameLast: string;

  @ApiProperty({
    description: "The suffix of the user's name",
    example: 'Jr.',
  })
  @IsString()
  nameSuffix: string;

  constructor(model: Partial<UserDto>) {
    this.id = model.id;
    this.companyID = model.companyID;
    this.organizationID = model.organizationID;
    this.individualAccount = model.individualAccount;
    this.email = model.email;
    this.banned = model.banned;
    this.isActivated = model.isActivated;
    this.rescueEmail = model.rescueEmail;
    this.namePreferred = model.namePreferred;
    this.namePrefix = model.namePrefix;
    this.nameFirst = model.nameFirst;
    this.nameMiddle = model.nameMiddle;
    this.nameLast = model.nameLast;
    this.nameSuffix = model.nameSuffix;
    this.phone = model.phone;
    this.isTwoFactorAuthenticationEnabled = model.isTwoFactorAuthenticationEnabled;
    this.requirePassReset = model.requirePassReset;
    this.hasAcceptedLatestTOS = model.hasAcceptedLatestTOS;
  }
}
