import { forwardRef, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { RoleService } from '../roles/roles.service';
import { MailService } from '../mail/mail.service';
import { RolesModule } from '../roles/roles.module';
import { RefreshTokenSessionsEntity } from './entity/refresh-token.entity';
import { UserEntity } from '../users/entity/user.entity';
import { UserRoleEntity } from '../roles/entity/user-role.entity';
import { RoleEntity } from '../roles/entity/role.entity';
import { OTPEntity } from './entity/otp.entity';

@Module({
  controllers: [AuthController],
  providers: [
    AuthService,
    RoleService,
    MailService
  ],
  imports: [
    JwtModule.register({
      secret: process.env.JWT_ACCESS_SECRET || 'SERCRET',
      signOptions: {
        expiresIn: '10m',
      },
    }),
    TypeOrmModule.forFeature([
      RefreshTokenSessionsEntity,
      UserEntity,
      UserRoleEntity,
      RoleEntity,
      OTPEntity,
    ]),
    RolesModule,
    forwardRef(() => UsersModule),
  ],
  exports: [
    AuthService,
    JwtModule,
  ],
})
export class AuthModule {}