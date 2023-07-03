import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity({
    name: "tos-text"
})
export class TOSTextEntity {
  @PrimaryGeneratedColumn()
  ID: number;

  @Column({ type: 'text' })
  text: string;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;
  
}