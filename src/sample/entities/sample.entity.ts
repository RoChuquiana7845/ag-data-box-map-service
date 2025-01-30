import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { Area } from '../../area/entities/area.entity';
import { User } from '../../user/entities/user.entity';
import { Attribute } from '../../attribute/entities/attribute.entity';

@Entity('samples')
export class Sample {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description: string;

  @Column({ type: 'varchar', nullable: true })
  table_name: string;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  registration_date: Date;

  @Column({ type: 'varchar', nullable: true })
  formatted_date: string;

  @ManyToOne(() => Area, (area) => area.samples, { nullable: false })
  area: Area;

  @ManyToOne(() => Attribute, { nullable: true })
  attribute: Attribute;

  @Column({ type: 'int', nullable: true })
  pixel_x: number;

  @Column({ type: 'int', nullable: true })
  pixel_y: number;

  @Column({ type: 'varchar', nullable: true })
  variable_selection_method: string;

  @Column({ type: 'float', nullable: true })
  original_variance_percentage: number;

  @Column({ type: 'varchar', nullable: true })
  sample_table: string;

  @ManyToOne(() => User, { nullable: false })
  user: User;

  @Column({ type: 'geometry', spatialFeatureType: 'Point', srid: 4326 })
  geom: Geometry;
}
