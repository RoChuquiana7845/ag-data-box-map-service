import { Module } from '@nestjs/common';
import { SampleGridController } from './sample-grid.controller';
import { SampleGridService } from './sample-grid.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SampleGrid } from './entities/sample-grid.entity';

@Module({
  imports: [TypeOrmModule.forFeature([SampleGrid])],
  controllers: [SampleGridController],
  providers: [SampleGridService],
})
export class SampleGridModule {}
