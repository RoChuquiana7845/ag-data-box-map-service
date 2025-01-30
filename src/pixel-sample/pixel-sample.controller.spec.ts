import { Test, TestingModule } from '@nestjs/testing';
import { PixelSampleController } from './pixel-sample.controller';

describe('PixelSampleController', () => {
  let controller: PixelSampleController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PixelSampleController],
    }).compile();

    controller = module.get<PixelSampleController>(PixelSampleController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
