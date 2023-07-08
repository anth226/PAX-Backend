export enum RolesTypes {
  USER = 'USER',
  COMPANY = 'COMPANY',
  ADMIN = 'ADMIN',
}

export type Role = RolesTypes.USER | RolesTypes.COMPANY | RolesTypes.ADMIN;
