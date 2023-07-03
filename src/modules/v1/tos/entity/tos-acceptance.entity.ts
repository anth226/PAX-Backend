import { Entity, Column, PrimaryGeneratedColumn, ManyToOne } from 'typeorm';
import { TOSTextEntity } from './tos.entity';

@Entity({
    name: "tos-acceptance"
})
export class TOSAcceptanceEntity {
  @PrimaryGeneratedColumn()
  ID: number;

  @Column({ type: 'bigint' })
  UserID: number;

  @ManyToOne(() => TOSTextEntity)
  TOSText: TOSTextEntity;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  AcceptanceDateTime: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

}
