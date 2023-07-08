import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  BaseEntity,
  PrimaryColumn,
} from 'typeorm';

@Entity({
  name: 'otp',
})
export class OTPEntity extends BaseEntity {
  @Column({ unique: true, nullable: true })
  email: string;

  @Column({ nullable: true })
  phone: string;

  @PrimaryColumn()
  identifier: string;

  @Column({ nullable: true })
  code: string;

  @Column()
  expiresIn: string;

  @Column()
  resendIn: string;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;
}
