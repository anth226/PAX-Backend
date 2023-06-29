import { IsBoolean, IsString, IsNumber, IsOptional, IsDate } from 'class-validator';

export class UserDto {
  @IsNumber()
  id: number;

  @IsOptional()
  @IsNumber()
  companyID: number;

  @IsOptional()
  @IsNumber()
  organizationID: number;

  @IsBoolean()
  individualAccount: boolean;

  @IsBoolean()
  banned: boolean;

  @IsBoolean()
  isActivated: boolean;

  @IsString()
  email: string;

  @IsOptional()
  @IsString()
  rescueEmail: string;

  @IsString()
  namePreferred: string;

  @IsString()
  namePrefix: string;

  @IsString()
  nameFirst: string;

  @IsString()
  nameMiddle: string;

  @IsString()
  nameLast: string;

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
  }  
}
