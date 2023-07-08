import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  JoinTable,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  BaseEntity,
} from 'typeorm';
import { UserEntity } from '../../users/entity/user.entity';

@Entity({
  name: 'tokens',
})
export class RefreshTokenSessionsEntity extends BaseEntity {
  @PrimaryGeneratedColumn()
  id: string;

  @ManyToOne(() => UserEntity, (userEntity: UserEntity) => userEntity.id)
  @JoinTable({ name: 'userId' })
  user: UserEntity;

  @Column({ nullable: true })
  public refreshToken: string;

  @Column({ nullable: false })
  ip: string;

  @Column({ nullable: true })
  os: string;

  @Column()
  ua: string;

  @Column({ nullable: true })
  fingerprint: string;

  @Column()
  expiresIn: string;

  @CreateDateColumn({
    name: 'creation_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  public created_at: Date;

  @UpdateDateColumn({
    name: 'updated_at',
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  public updated_at: Date;
}
