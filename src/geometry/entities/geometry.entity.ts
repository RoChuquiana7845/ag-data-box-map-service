import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  Index,
} from 'typeorm';
import { Area } from 'src/area/entities/area.entity';

@Entity('geometries')
export class Geometry {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Area, { nullable: false, onDelete: 'CASCADE' })
  @Index()
  area: Area;

  @Column({ type: 'jsonb' })
  geom: {
    type: 'Polygon';
    coordinates: number[][][];
  };

  @Column({ type: 'jsonb' })
  style: {
    fillColor: string;
    strokeColor: string;
    fillOpacity: number;
    strokeWidth: number;
  };
}
