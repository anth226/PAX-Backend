import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { RolesModule } from '../roles/roles.module';
import { MailModule } from '../mail/mail.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from './users.controller';
import { UserService } from './users.service';
import { UserEntity } from './entity/user.entity';
import { UserRoleEntity } from '../roles/entity/user-role.entity';
import { RefreshTokenSessionsEntity } from '../auth/entity/refresh-token.entity';

@Module({
  controllers: [UserController],
  providers: [UserService],
  imports: [
    TypeOrmModule.forFeature([
      UserEntity,
      UserRoleEntity,
      RefreshTokenSessionsEntity,
    ]),
    RolesModule,
    MailModule,
  ],
  exports: [UserService],
})
export class UsersModule {}