import {
  Entity,
  Column,
  BaseEntity,
  PrimaryGeneratedColumn,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  JoinColumn,
  OneToOne,
} from 'typeorm';
import { UserRoleEntity } from '../../roles/entity/user-role.entity';
import { LoginAttemptEntity } from '../../auth/entity/login-attempt.entity';
import { LoginLogEntity } from '../../auth/entity/login-logging.entity';
import { TwoFactorMethodEntity } from '../../auth/entity/two-factor.entity';


@Entity({
  name: 'users',
})
export class UserEntity extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: true })
  companyID: number;

  @Column({ nullable: true })
  organizationID: number;

  @Column({default: true})
  individualAccount: boolean;

  @Column({unique:true})
  email: string;

  @Column({ nullable: true })
  rescueEmail: string;

  @Column({ nullable: true })
  resetLink: string;

  @Column({ nullable: true })
  resetLinkExpiresIn: string;

  @Column({ nullable: true })
  activationLink: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ nullable: true })
  namePreferred: string;

  @Column({ nullable: true })
  namePrefix: string;

  @Column({ nullable: true })
  nameFirst: string;

  @Column({ nullable: true })
  nameMiddle: string;

  @Column({ nullable: true })
  nameLast: string;

  @Column({ nullable: true })
  nameSuffix: string;

  @Column()
  password: string;

  @Column({default:false})
  isActivated: boolean;

  @Column({default:false})
  banned: boolean;
  
  @Column({ default: false })
  requirePassReset: boolean;

  @Column({default:false})
  isTwoFactorAuthenticationEnabled: boolean;

  @Column({ type: 'boolean', default: false })
  hasAcceptedLatestTOS: boolean;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  passwordChangeDateTime: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

  @OneToMany(() => UserRoleEntity, (userRoleEntity: UserRoleEntity) => userRoleEntity.user)
  public userRoleEntity!: UserRoleEntity[];

  @OneToMany(() => LoginAttemptEntity, loginAttempt => loginAttempt.user)
  public loginAttempts: LoginAttemptEntity[];

  @OneToMany(() => LoginLogEntity, log => log.user)
  public logs: LoginLogEntity[];

  @OneToMany(() => TwoFactorMethodEntity, method => method.user)
  twoFactorMethods: TwoFactorMethodEntity[];

  @OneToOne(() => TwoFactorMethodEntity)
  @JoinColumn()
  defaultTwoFactorMethod: TwoFactorMethodEntity;

}