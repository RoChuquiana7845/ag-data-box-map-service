import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
} from 'typeorm';
import { Geometry } from 'geojson';
import { User } from '../../user/entities/user.entity';
import { Sample } from '../../sample/entities/sample.entity';

@Entity('areas')
export class Area {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column()
  description: string;

  @Column({ type: 'float' })
  size: number;

  @Column({ type: 'uuid', nullable: true })
  soil_type: string;

  @Column({ type: 'uuid', nullable: true })
  project: string;

  @Column({ type: 'geometry', spatialFeatureType: 'Polygon', srid: 4326 })
  geom: Geometry;

  @OneToMany(() => Sample, (sample) => sample.area)
  samples: Sample[];

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  registration_date: Date;

  @ManyToOne(() => User, (user) => user.id, { nullable: false })
  user: User;
}
