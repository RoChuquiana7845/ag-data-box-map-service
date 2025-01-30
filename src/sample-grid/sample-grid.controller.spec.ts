import { Test, TestingModule } from '@nestjs/testing';
import { SampleGridController } from './sample-grid.controller';

describe('SampleGridController', () => {
  let controller: SampleGridController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SampleGridController],
    }).compile();

    controller = module.get<SampleGridController>(SampleGridController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
