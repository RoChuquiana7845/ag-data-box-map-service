import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Classification } from '../../classification/entities/classification.entity';

@Entity('classification_levels')
export class ClassificationLevel {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column({ type: 'int' })
  level: number;

  @Column({ type: 'float' })
  minimum_value: number;

  @Column({ type: 'float' })
  maximum_value: number;

  @Column()
  color: string;

  @ManyToOne(() => Classification, { nullable: false })
  classification: Classification;
}
