import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { Map } from '../../map/entities/map.entity';

@Entity('pixel_maps')
export class PixelMap {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column({ type: 'geometry', spatialFeatureType: 'Point', srid: 4326 })
  geom: Geometry;

  @Column({ type: 'float' })
  value: number;

  @ManyToOne(() => Map, { nullable: false })
  map: Map;
}
