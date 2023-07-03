import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { UserEntity } from '../../users/entity/user.entity';

@Entity({
    name: "two-factor-authentication"
})
export class TwoFactorMethodEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  methodType: string; // e.g., 'phone', 'email', 'authenticator app'

  @Column()
  methodDetail: string; // e.g., phone number, email address, code

  @ManyToOne(() => UserEntity, user => user.twoFactorMethods)
  user: UserEntity;
}
