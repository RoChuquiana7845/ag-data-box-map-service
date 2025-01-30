import { Entity, PrimaryGeneratedColumn, Column, ManyToOne } from 'typeorm';
import { Geometry } from 'geojson';
import { SampleGrid } from '../../sample-grid/entities/sample-grid.entity';

@Entity('sample_points')
export class SamplePoint {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  code: string;

  @Column({ type: 'geometry', spatialFeatureType: 'Point', srid: 4326 })
  geom: Geometry;

  @ManyToOne(() => SampleGrid, { nullable: false })
  sample_grid: SampleGrid;
}
