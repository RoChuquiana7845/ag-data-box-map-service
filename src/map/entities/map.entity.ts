import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { User } from '../../user/entities/user.entity';
import { Sample } from '../../sample/entities/sample.entity';
import { Area } from '../../area/entities/area.entity';
import { Classification } from '../../classification/entities/classification.entity';

@Entity('maps')
export class Map {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  creation_date: Date;

  @Column({ type: 'varchar' })
  map_table_name: string;

  @Column({ type: 'float', nullable: true })
  width: number;

  @Column({ type: 'float', nullable: true })
  height: number;

  @Column({ type: 'varchar', nullable: true })
  geometry_type: string;

  @Column({ type: 'varchar', nullable: true })
  interpolator_type: string;

  @Column({ type: 'float', nullable: true })
  exponent: number;

  @Column({ type: 'float', nullable: true })
  radius: number;

  @Column({ type: 'int', nullable: true })
  points_count: number;

  @Column({ type: 'float', nullable: true })
  nugget_effect: number;

  @Column({ type: 'float', nullable: true })
  sill: number;

  @Column({ type: 'float', nullable: true })
  range: number;

  @Column({ type: 'geometry', spatialFeatureType: 'Polygon', srid: 4326 })
  geom: Geometry;

  @ManyToOne(() => Classification, { nullable: true })
  classification: Classification;

  @ManyToOne(() => Sample, { nullable: true })
  sample: Sample;

  @ManyToOne(() => Area, { nullable: true })
  area: Area;

  @ManyToOne(() => User, { nullable: false })
  user: User;
}
