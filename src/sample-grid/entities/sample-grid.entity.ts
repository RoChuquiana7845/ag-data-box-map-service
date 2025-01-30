import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { Area } from '../../area/entities/area.entity';
import { User } from '../../user/entities/user.entity';

@Entity('sample_grids')
export class SampleGrid {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description: string;

  @Column({ type: 'varchar', nullable: true })
  table_name: string;

  @ManyToOne(() => Area, { nullable: false })
  area: Area;

  @Column({ type: 'float' })
  width: number;

  @Column({ type: 'float' })
  height: number;

  @ManyToOne(() => User, { nullable: false })
  user: User;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  registration_date: Date;

  @Column({ type: 'varchar', nullable: true })
  formatted_date: string;

  @Column({ type: 'boolean', default: false })
  sensor_flag: boolean;

  @Column({ type: 'geometry', spatialFeatureType: 'Polygon', srid: 4326 })
  geom: Geometry;
}
