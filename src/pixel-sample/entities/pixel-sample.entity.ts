import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { Sample } from '../../sample/entities/sample.entity';

@Entity('pixel_samples')
export class PixelSample {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column({ type: 'geometry', spatialFeatureType: 'Point', srid: 4326 })
  geom: Geometry; // Ubicación del píxel en el mapa

  @Column({ type: 'float' })
  value: number;

  @ManyToOne(() => Sample, { nullable: false })
  sample: Sample;
}
