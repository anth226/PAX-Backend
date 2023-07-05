import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { TOSTextEntity } from './tos.entity';
import { UserEntity } from '../../users/entity/user.entity';

@Entity({
    name: "tos-acceptance"
})
export class TOSAcceptanceEntity {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => UserEntity)
  user: UserEntity;

  @ManyToOne(() => TOSTextEntity)
  tosText: TOSTextEntity;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  acceptanceDateTime: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

}
