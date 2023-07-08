import {
  Entity,
  Column,
  BaseEntity,
  PrimaryGeneratedColumn,
  // ManyToMany,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
} from 'typeorm';
import { UserRoleEntity } from './user-role.entity';

@Entity({
  name: 'roles',
})
export class RoleEntity extends BaseEntity {
  @PrimaryGeneratedColumn('increment')
  public id: number;

  @Column({ unique: true })
  value: string;

  @Column()
  description: string;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP(6)' })
  public created_at: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  public updated_at: Date;

  @OneToMany(() => UserRoleEntity, (userRoleEntity: UserRoleEntity) => userRoleEntity.role)
  public userRoleEntity!: UserRoleEntity[];
}
