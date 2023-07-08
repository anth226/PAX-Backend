import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { UserEntity } from '../../users/entity/user.entity';

@Entity({
  name: 'login-logging',
})
export class LoginLogEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  ip: string;

  @Column()
  userAgent: string;

  @Column()
  loginMethod: string;

  @Column({ default: true })
  otpStatus: boolean;

  @Column({ nullable: true })
  location: string;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

  @ManyToOne(() => UserEntity, user => user.logs)
  public user: UserEntity;
}
