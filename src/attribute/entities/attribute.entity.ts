import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { UnitMeasure } from '../../unit-measure/entities/unit-measure.entity';

@Entity('attributes')
export class Attribute {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description_pt: string;

  @Column()
  acronym_pt: string;

  @Column()
  description_en: string;

  @Column()
  acronym_en: string;

  @Column()
  description_es: string;

  @Column()
  acronym_es: string;

  @ManyToOne(() => UnitMeasure, { nullable: true, eager: true })
  unit?: UnitMeasure;
}
