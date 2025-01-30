import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { Area } from '../../area/entities/area.entity';
import { User } from '../../user/entities/user.entity';

@Entity('management_regions')
export class ManagementRegion {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  description: string;

  @Column({ type: 'varchar', unique: true })
  zone_table_name: string;

  @Column({ type: 'int' })
  zone_class_count: number;

  @Column({ type: 'varchar' })
  zone_creation_method: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  date: Date;

  @Column({ type: 'int', nullable: true })
  iterations: number;

  @Column({ type: 'float', nullable: true })
  exponent: number;

  @Column({ type: 'float', nullable: true })
  error: number;

  @Column({ type: 'float', nullable: true })
  fpi: number;

  @Column({ type: 'float', nullable: true })
  mpe: number;

  @ManyToOne(() => Area, { nullable: false })
  area: Area;

  @Column({ type: 'varchar', nullable: true })
  anova: string;

  @Column({ type: 'varchar', nullable: true })
  vr: string;

  @Column({ type: 'varchar', nullable: true })
  asc_zm: string;

  @ManyToOne(() => User, { nullable: false })
  user: User;

  @Column({ type: 'geometry', spatialFeatureType: 'Polygon', srid: 4326 })
  geom: Geometry;
}
