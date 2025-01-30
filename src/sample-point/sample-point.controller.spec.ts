import { Test, TestingModule } from '@nestjs/testing';
import { SamplePointController } from './sample-point.controller';

describe('SamplePointController', () => {
  let controller: SamplePointController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [SamplePointController],
    }).compile();

    controller = module.get<SamplePointController>(SamplePointController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
