import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { User } from '../../user/entities/user.entity';

@Entity('unit_measures')
export class UnitMeasure {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description: string;

  @Column()
  acronym: string;

  @ManyToOne(() => User, { nullable: false })
  user: User;
}
