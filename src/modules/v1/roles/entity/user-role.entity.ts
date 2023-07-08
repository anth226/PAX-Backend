import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  JoinColumn,
  BaseEntity,
} from 'typeorm';
import { UserEntity } from '../../users/entity/user.entity';
import { RoleEntity } from './role.entity';

@Entity({
  name: 'user-roles',
})
export class UserRoleEntity extends BaseEntity {
  @PrimaryGeneratedColumn()
  public id?: number;

  @Column()
  public roleId: number;

  @Column()
  public userId: number;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP(6)' })
  public created_at?: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  public updated_at?: Date;

  @ManyToOne(() => RoleEntity, role => role.userRoleEntity)
  @JoinColumn({ name: 'roleId' })
  public role?: RoleEntity;

  @ManyToOne(() => UserEntity, user => user.userRoleEntity)
  @JoinColumn({ name: 'userId' })
  public user?: UserEntity;
}
