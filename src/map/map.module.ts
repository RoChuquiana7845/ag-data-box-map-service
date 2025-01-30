import { Module } from '@nestjs/common';
import { MapController } from './map.controller';
import { MapService } from './map.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Map } from './entities/map.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Map])],
  controllers: [MapController],
  providers: [MapService],
  exports: [MapService],
})
export class MapModule {}
